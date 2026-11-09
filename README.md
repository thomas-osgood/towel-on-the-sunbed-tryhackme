# Towel On The Sunbed

## Vulnerability Description

The `/claim` endpoint can be hit multiple times in short order (prior to the claim being marked as acquired), causing the user to acquire more points than the developers intended. This is konwn as a race condition.

Some references to learn more abour race conditions are:

- [Huntress](https://www.huntress.com/cybersecurity-101/topic/what-is-race-condition)
- [Snyk](https://learn.snyk.io/lesson/race-condition/?ecosystem=python)
- [GeeksForGeeks](https://www.geeksforgeeks.org/operating-systems/race-condition-in-operating-systems/)

## Exploit

The exploitation of the race condition can be accomplished multiple ways.

### BurpSuite

The first is via BurpSuite. In BurpSuite the user can capture a request (to the dashboard, for example), send it to the Repeater tab and modify it so it is a `POST /claim` request. After the request has been modified to point to the correct endpoint and use the correct method, the user can then create a `tab group` and clone the request `N` times. To run the exploit, the user can click the triangle that appears next to the `send` button and choose `send in parallel` to have all requests sent at the same time. This will result in the user acquiring `50 x N` points.

### Sunbed

The second way is using the [Golang Sunbet Exploit](./sunbed.go) contained within this repository. This tool will automatically generate and register a random `username:password`, exploit the race condition in the `/claim` endpoint and acquire the flag from the `/vault` endpoint.

Args:

- target: the IP or Domain of the target server (string)
- port: the port the site is running on. (int)
- secure: flag indicating whether or not to use https. (bool)
- workers: number of workers used in race condition exploit. (int)
