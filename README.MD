# A Lark Bot to Ping Remote Server

The bot will ping the remote server every `timeout` and calculate the `ratio` of the successful ping requests in the `window`.
If the `ratio` is less than the threshold, the bot will post a message to the Lark group.

Bot only post event when the status changes.

```shell
RUST_LOG=ping_bot=trace cargo run -- --help
Check Remote Server is available and post message to Feishu

Usage: ping-bot [OPTIONS] --address <ADDRESS> --webhook <WEBHOOK> --secret <SECRET>

Options:
  -a, --address <ADDRESS>  
  -t, --timeout <TIMEOUT>  [default: 1]
  -r, --ratio <RATIO>      [default: 0.9]
      --window <WINDOW>    [default: 60]
  -w, --webhook <WEBHOOK>  
  -s, --secret <SECRET>    
  -h, --help               Print help
  -V, --version            Print version
```

## Arguments
* `--address` - The address of the remote server.
* `--timeout` - The timeout in seconds for the ping request. Default is 1 second.
* `--ratio` - The ratio of the successful ping requests in the window to trigger the alert. Default is 0.9.
* `--window` - The window in seconds to calculate the ratio. Default is 60 seconds.
* `--webhook` - The webhook URL of the Lark bot.
* `--secret` - The secret of the Lark bot.

## Example
```shell
RUST_LOG=ping_bot=trace cargo run -- \
  -a 37.*.*.* \
  -t 1 \
  -w https://open.feishu.cn/open-apis/bot/v2/hook/ab5229c4-*** \
  -s ***
```
