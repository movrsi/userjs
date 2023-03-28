## userjs
My personal userjs file for Mozilla Firefox.

## What is userjs
A user.js file can make certain preference settings more or less "permanent" in a specific profile, since you'll have to first delete or edit the user.js file to remove the entries before the preferences can be changed in the application. This has the advantage of locking in certain preference settings. A user.js file is also a way of documenting preference customizations and it makes it easier to transfer customized settings to another profile.
>https://kb.mozillazine.org/User.js_file

## Installation
The following is information for installing `userjs` for a single profile, this is the method i have used for my configuration.

| OS                         | Path                                                                                                                                          |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows                  | `%APPDATA%\Mozilla\Firefox\Profiles\XXXXXXXX.your_profile_name\user.js`                                                                       |
| Linux                      | `~/.mozilla/firefox/XXXXXXXX.your_profile_name/user.js`                                                                                       |
| OS X                       | `~/Library/Application Support/Firefox/Profiles/XXXXXXXX.your_profile_name`                                                                   |
| Android                    | `/data/data/org.mozilla.firefox/files/mozilla/XXXXXXXX.your_profile_name` |

## Additional Hardening / Privacy (Add-ons)
I reccommend the following addons for extended privacy and hardening of Mozilla Firefox.
* https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/ - Ad blocker, tracking protection, social media blocking.
* https://addons.mozilla.org/en-US/firefox/addon/noscript/ - Block untrusted javascript and build your own trust within the world wide web.
* https://addons.mozilla.org/en-US/firefox/addon/canvasblocker/ - Block canvas access and spoof details to prevent fingerprinting of your browser.
* https://addons.mozilla.org/en-US/firefox/addon/decentraleyes/ - More tracking prevention and also keeps a local copy of resources to prevent tracking of websites you visit.

## Credit
Special thanks to the following users for their efforts for their own take on the Mozilla Firefox user.js configurations.

@pyllyukko
@hnhx

The Tor Project and many others.
