# Browser automation module

Browser testing is an optional module independent of existing HTTP scanner wrappers. No browser is started by the core scan lifecycle.

* **Playwright** provides a cross-browser automation API and trace/video tooling. Install a pinned Python dependency with `pip install playwright` then `playwright install chromium`; Windows 11 is supported. Official [installation](https://playwright.dev/python/docs/intro) and [Docker](https://playwright.dev/docs/docker) docs. The official container image includes browsers/system libraries, but the matching Playwright package version must be installed. Upstream warns against visiting untrusted websites in its development image.
* **Chrome DevTools Protocol (CDP)** is Chrome's debugging protocol, not a standalone scanner. Start a dedicated browser profile with a loopback-only debugging port; use [protocol docs](https://chromedevtools.github.io/devtools-protocol/) and [Chrome remote debugging guidance](https://developer.chrome.com/docs/devtools/remote-debugging/). Never expose the debugging port to a network or attach to a personal profile.
* **Chrome Headless** supports automation/screenshot/PDF workflows. See [official headless docs](https://developer.chrome.com/docs/chromium/headless). Executable/package installation follows Chrome's platform installers; pin browser versions in CI.

Design boundary: separate worker process/container, isolated temporary browser profile, allowlisted test target, explicit timeout/cancellation, bounded downloads, and redacted artifacts. Tool Manager currently describes these tools but does not launch them. Browser output (trace, screenshot, console/network records) needs a purpose-built result adapter before report ingestion.
