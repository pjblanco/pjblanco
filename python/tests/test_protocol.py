import asyncio
import unittest

from remote_support.protocol import ProtocolError, read_message, write_message


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_lines_round_trip(self) -> None:
        received = []

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            received.append(await read_message(reader))
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await write_message(writer, {"type": "hello", "role": "viewer"})
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0)
        server.close()
        await server.wait_closed()
        self.assertEqual(received, [{"type": "hello", "role": "viewer"}])

    async def test_non_object_is_rejected(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"[1, 2, 3]\n")
        reader.feed_eof()
        with self.assertRaises(ProtocolError):
            await read_message(reader)


if __name__ == "__main__":
    unittest.main()
