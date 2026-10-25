from __future__ import annotations

import uvicorn

from common.settings import AsgiServerSettings


def main() -> None:
    settings = AsgiServerSettings()
    uvicorn.run(
        settings.app,
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
    )


if __name__ == "__main__":
    main()
