

import argparse, asyncio

import uvicorn

from .app import app


async def runapp():

    parser = argparse.ArgumentParser(usage="weblogin [options]",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="Web server illustrating login capabilities.",
                                     epilog="""
If not set here, the host and port defaults are 'localhost:8000'.
The database file holds user configuration, and is initially
created with user 'admin' and password 'password!', which can
be changed via browser using the 'edit' facility.
""")

    parser.add_argument("--port", default="8000", type=int, help="Listening port of the web server.")
    parser.add_argument("--host", default="localhost", help="Hostname/IP of the web server.")

    args = parser.parse_args()

    print(f"Serving on {args.host}:{args.port}")
    config = uvicorn.Config(app=app, host=args.host, port=args.port, log_level="error")
    server = uvicorn.Server(config)
    await server.serve()


def main():
    "Run the program"
    asyncio.run(runapp())


if __name__ == "__main__":
    # And run main
    main()
