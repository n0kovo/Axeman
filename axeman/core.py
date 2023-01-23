import argparse
import asyncio
from collections import deque

import uvloop

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

import base64
import hashlib
import locale
import logging
import math
import os
import sys
import traceback
from tqdm.asyncio import tqdm

import aiohttp
import aioprocessing
from rich import box
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.logging import RichHandler
from rich.status import Status

try:
    locale.setlocale(locale.LC_ALL, "en_US")
except:
    pass

from icecream import ic
from OpenSSL import crypto

from . import certlib

DOWNLOAD_CONCURRENCY = 50
MAX_QUEUE_SIZE = 1000

console = Console()


async def download_worker(session, log_info, work_deque, download_queue, rich_status):
    while True:
        try:
            start, end = work_deque.popleft()
        except IndexError:
            return

        logging.debug(f"[blue][{log_info['url']}] Queueing up blocks {start}-{end}...")

        for x in range(3):
            try:
                async with session.get(
                    certlib.DOWNLOAD.format(log_info["url"], start, end)
                ) as response:
                    entry_list = await response.json()
                    # logging.debug(f"[green][{log_info['url']}] Retrieved blocks {start}-{end}...")
                    break
            except Exception as e:
                logging.error(f"[red]Exception getting block {start}-{end}! {e}")
        else:  # Notorious for else, if we didn't encounter a break our request failed 3 times D:
            with open("/tmp/fails.csv", "a") as f:
                f.write(",".join([log_info["url"], str(start), str(end)]))
            return

        for index, entry in zip(range(start, end + 1), entry_list["entries"]):
            entry["cert_index"] = index

        await download_queue.put(
            {
                "entries": entry_list["entries"],
                "log_info": log_info,
                "start": start,
                "end": end,
            }
        )


async def queue_monitor(log_info, work_deque, download_results_queue, rich_status):
    total_size = log_info["tree_size"] - 1
    total_blocks = math.ceil(total_size / log_info["block_size"])

    while True:
        queue_size = len(download_results_queue._queue)
        dl_count = total_blocks - len(work_deque)
        status_1 = "[blue]Queue Status:[/blue] [magenta]Processing[magenta]    [blue]Queue Size:[/blue] "
        status_2 = "[blue]Downloaded blocks:[/blue] "
        count = f"[blue]{dl_count} / {total_blocks}[/blue] "
        percentage = f"[cyan]({dl_count/total_blocks:.4%})[/cyan]"
        formatted = f"{status_1}{queue_size:<10}{status_2}{count:<20}{percentage:<15}\t"
        logging.info(formatted)
        await asyncio.sleep(2)


async def retrieve_certificates(
    loop,
    rich_status,
    url=None,
    ctl_offset=0,
    output_directory="/tmp/",
    concurrency_count=DOWNLOAD_CONCURRENCY,
):
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        ctl_logs = await certlib.retrieve_all_ctls(session)

        logging.info(f"[blue]Starting work!")

        if url:
            url = url.strip("'")

        for log in ctl_logs:
            if url and url not in log["url"]:
                continue
            work_deque = deque()
            download_results_queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)

            logging.info(f"[blue]Downloading certificates for {log['description']}")
            try:
                log_info = await certlib.retrieve_log_info(log, session)
            except (
                aiohttp.ClientConnectorError,
                aiohttp.ServerTimeoutError,
                aiohttp.ClientOSError,
                aiohttp.ClientResponseError,
            ) as e:
                logging.info(f"[red]Failed to connect to CTL! -> {e} - skipping.")
                continue

            try:
                await certlib.populate_work(work_deque, log_info, start=ctl_offset)
            except Exception as e:
                logging.info(f"[red]Log needs no update - {e}")
                continue

            download_tasks = asyncio.gather(
                *[
                    download_worker(
                        session, log_info, work_deque, download_results_queue, rich_status
                    )
                    for _ in range(concurrency_count)
                ]
            )

            processing_task = asyncio.ensure_future(
                processing_coro(
                    download_results_queue, rich_status, output_dir=output_directory
                )
            )
            queue_monitor_task = asyncio.ensure_future(
                queue_monitor(log_info, work_deque, download_results_queue, rich_status)
            )

            asyncio.ensure_future(download_tasks)

            await download_tasks

            await download_results_queue.put(
                None
            )  # Downloads are done, processing can stop

            await processing_task

            queue_monitor_task.cancel()

            logging.info(
                "[green]Completed {}, stored at {}!".format(
                    log_info["description"],
                    "/tmp/{}.csv".format(log_info["url"].replace("/", "_")),
                )
            )

            logging.info(
                f"[green]Finished downloading and processing {log_info['url']}"
            )


async def processing_coro(download_results_queue, rich_status, output_dir="/tmp"):
    logging.info(f"[blue]Starting processing coro and process pool")
    process_pool = aioprocessing.AioPool(initargs=(output_dir,))

    done = False

    while True:
        entries_iter = []
        logging.info(f"[blue]Getting things to process...")
        for _ in range(int(process_pool.pool_workers)):
            entries = await download_results_queue.get()
            if entries != None:
                entries_iter.append(entries)
            else:
                done = True
                break

        logging.info(
            f"[cyan]Got a chunk of {process_pool.pool_workers} - Mapping into process pool..."
        )

        for entry in entries_iter:
            csv_storage = f"{output_dir}/certificates/{entry['log_info']['url'].replace('/', '_')}"
            if not os.path.exists(csv_storage):
                logging.info(f"[blue][{os.getpid()}] Making dir...")
                os.makedirs(csv_storage)
            entry["log_dir"] = csv_storage

        if len(entries_iter) > 0:
            await process_pool.coro_starmap(process_worker, [(entries_iter, rich_status)])

        logging.info(f"[green]Done mapping! Got results")

        if done:
            break

    process_pool.close()

    await process_pool.coro_join()


def process_worker(result_info, rich_status):
    logging.debug(f"Worker {os.getpid()} starting...")
    if not result_info:
        return
    try:
        csv_storage = result_info["log_dir"]
        csv_file = f"{csv_storage}/{result_info['start']}-{result_info['end']}.csv"

        lines = []

        print(f"[{os.getpid()}] Parsing...")
        for entry in result_info["entries"]:
            mtl = certlib.MerkleTreeHeader.parse(base64.b64decode(entry["leaf_input"]))

            cert_data = {}

            if mtl.LogEntryType == "X509LogEntryType":
                cert_data["type"] = "X509LogEntry"
                chain = [
                    crypto.load_certificate(
                        crypto.FILETYPE_ASN1,
                        certlib.Certificate.parse(mtl.Entry).CertData,
                    )
                ]
                extra_data = certlib.CertificateChain.parse(
                    base64.b64decode(entry["extra_data"])
                )
                for cert in extra_data.Chain:
                    chain.append(
                        crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
                    )
            else:
                cert_data["type"] = "PreCertEntry"
                extra_data = certlib.PreCertEntry.parse(
                    base64.b64decode(entry["extra_data"])
                )
                chain = [
                    crypto.load_certificate(
                        crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData
                    )
                ]

                for cert in extra_data.Chain:
                    chain.append(
                        crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
                    )

            cert_data.update(
                {
                    "leaf_cert": certlib.dump_cert(chain[0]),
                    "chain": [certlib.dump_cert(x) for x in chain[1:]],
                }
            )

            certlib.add_all_domains(cert_data)

            cert_data["source"] = {
                "url": result_info["log_info"]["url"],
            }

            chain_hash = hashlib.sha256(
                "".join([x["as_der"] for x in cert_data["chain"]]).encode("ascii")
            ).hexdigest()

            # header = "url, cert_index, chain_hash, cert_der, all_domains, not_before, not_after"
            lines.append(
                ",".join(
                    [
                        result_info["log_info"]["url"],
                        str(entry["cert_index"]),
                        chain_hash,
                        cert_data["leaf_cert"]["as_der"],
                        " ".join(cert_data["leaf_cert"]["all_domains"]),
                        str(cert_data["leaf_cert"]["not_before"]),
                        str(cert_data["leaf_cert"]["not_after"]),
                    ]
                )
                + "\n"
            )

        print(f"[{os.getpid()}] Finished, writing CSV...")

        with open(csv_file, "w", encoding="utf8") as f:
            f.write("".join(lines))
        print(f"[{os.getpid()}] CSV {csv_file} written!")

    except Exception as e:
        print("========= EXCEPTION =========")
        traceback.print_exc()
        print(e)
        print("=============================")

    return True


async def get_certs_and_print():

    # Create table for printing
    table = Table(show_footer=False, expand=True, box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Name", no_wrap=True)
    table.add_column("URL", no_wrap=True)
    table.add_column("Owner", no_wrap=True)
    table.add_column("Cert Count", no_wrap=True)
    table.add_column("Max Block Size", no_wrap=True)

    # Live object for updating the table seamlessly
    with Live(table, refresh_per_second=4):
        async with aiohttp.ClientSession(conn_timeout=5) as session:
            ctls = await certlib.retrieve_all_ctls(session)
            print(f"Found {len(ctls)} CTLs...")
            for log in ctls:
                log_name = log["description"]
                try:
                    log_info = await certlib.retrieve_log_info(log, session)
                except Exception as e:
                    logging.debug(f"Could not retrieve {log_name}: {e}")
                    continue

                # Add CTL data as row
                row = (
                    str(log_name),
                    str(log["url"]),
                    str(log_info["operated_by"]),
                    str(locale.format("%d", log_info["tree_size"] - 1, grouping=True)),
                    str(log_info["block_size"]),
                )
                table.add_row(*row)


def main():
    with Status("Working...") as rich_status:

        loop = asyncio.get_event_loop()

        parser = argparse.ArgumentParser(
            description="Pull down certificate transparency list information"
        )

        parser.add_argument(
            "-f",
            dest="log_file",
            action="store",
            default="/tmp/axeman.log",
            help="location for the axeman log file",
        )

        parser.add_argument(
            "-s",
            dest="start_offset",
            action="store",
            default=0,
            help="Skip N number of lists before starting",
        )

        parser.add_argument(
            "-l",
            dest="list_mode",
            action="store_true",
            help="List all available certificate lists",
        )

        parser.add_argument(
            "-u",
            dest="ctl_url",
            action="store",
            default=None,
            help="Retrieve this CTL only",
        )

        parser.add_argument(
            "-z",
            dest="ctl_offset",
            action="store",
            default=0,
            help="The CTL offset to start at",
        )

        parser.add_argument(
            "-o",
            dest="output_dir",
            action="store",
            default="/tmp",
            help="The output directory to store certificates in",
        )

        parser.add_argument(
            "-v",
            dest="verbose",
            action="store_true",
            help="Print out verbose/debug info",
        )

        parser.add_argument(
            "-c",
            dest="concurrency_count",
            action="store",
            default=50,
            type=int,
            help="The number of concurrent downloads to run at a time",
        )

        args = parser.parse_args()

        if args.list_mode:
            loop.run_until_complete(get_certs_and_print())
            return

        handlers = [RichHandler(markup=True), logging.FileHandler(args.log_file)]

        if args.verbose:
            logging.basicConfig(
                format="%(message)s", level=logging.DEBUG, handlers=handlers
            )
        else:
            logging.basicConfig(
                format="%(message)s", level=logging.INFO, handlers=handlers
            )

        logging.info("[blue]Starting...")

        if args.ctl_url:
            loop.run_until_complete(
                retrieve_certificates(
                    loop,
                    rich_status,
                    url=args.ctl_url,
                    ctl_offset=int(args.ctl_offset),
                    concurrency_count=args.concurrency_count,
                    output_directory=args.output_dir,
                )
            )
        else:
            loop.run_until_complete(
                retrieve_certificates(
                    loop,
                    rich_status,
                    concurrency_count=args.concurrency_count,
                    output_directory=args.output_dir,
                )
            )


if __name__ == "__main__":
    main()
