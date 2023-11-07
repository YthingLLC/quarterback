## Quarterback

A simple, no nonsense, *anything* runner. 

### What is it?

Quarterback is a "freeform" task/action/whatever you want to call it runner. 

Quarterback has no care in the world what it is that it's doing. 

Quarterback will run and complete actions written in any language, on *anything*.

Do you have a routine need to run tasks on your WiFi enabled toaster? Quarterback can do it.

Want to give your users a "click here" button for some server command that you don't want to build an entire UI for?

Want to run tasks on your server based upon *any* webhook? Say... build a Git repo on your server, without tying yourself down to an gigantic, opinionated, CI/CD system?
Do you *really* want to avoid learning yet another systems way of doing things, and just have an external hook into your existing shell scripts?

Quarterback is meant to make it *simple* to execute *anything*, *anywhere* from a single HTTP request. 

Think of this as an even more flexible "AppRise," that's not just limited to sending notifications.
    
Quarterback, *can* provide a standard "API" to send notifications, but it is not "batteries included."
For example, Quarterback can make a request via the appropriate curl command to another API, with whatever
translation you need to do in between. Even a simple shell script will do.

### Why?

I have, over the many years of managing Linux servers, built up a lot of shell scripts and utilities that are generally specific to the environment in which they are deployed.

They're useful. They automate some routine task that benefits greatly from automation. Either do to the regularity of the task, or from the infrequency in which it is completed. 

Of which, I have found both scenarios benefit from solid documentation of the task in the form of... shell scripts.
Yes. shell scripts. Almost all server management tasks boil down to "shell scripts." Manually inputting commands? That's just a shell script with extra steps.

This contrasts against a configuration management tool, like Ansible, as it's less about "configuration management" and more of a desire to have a simpler way to trigger tasks on remote systems,
which can not be automated with something like cron. 

An example of this: triggering a deployment to a production server. I have, always, made my final deployments to production as a manual process. I will *always* do so. 

I believe strongly that any live production system should have it's final "guard" be a human doing something to "approve" the deployment. 

This has allowed me to give, less 'technical' users, the ability to "self-manage" some kind of deployment I have made for them.

I have built 'guard rails' around what can be managed, by wrapping some of the common management tasks into small shell scripts and utilities. 

I have built Quarterback out of a desire to provide those same users a "click here" link for those same actions. 
Saving them from needing to learn how to use SSH or the command line to interact with the shell scripts for their environment.

### What? How?

Quarterback is built to be as simple, lightweight, and generic as possible. It has no opinions on *what* it is actually doing. It only knows what it can do, and who is allowed to do it.

Quarterback is built with user friendliness and respectfulness in mind, to all users of the software. 

  - From the "end users" perspective it's a simple and easy to use link that does what they need it to do.
  - From the "administrators" perspective it's a highly configurable action runner, that is easy to use and configure.

Quarterback has a built in, interactive, "configurator." This configurator respects the administrator, and understands that it is impossible to remember how anything works. 
Spend enough time managing enough of *anything* and it becomes impossible to remember it all. 

Quarterback is built around a design to be *forgotten*. It does not expect you to memorize some esoteric command set, or force you to dig through pages and pages of documentation to "just work."
The interactive configurator can handle all possible configuration that Quarterback can then "manage" for you. All of the commands provide useful error messages, with examples on how they work. 
All of the commands follow a similar pattern, to simplify their "neural storage efficiency" (i.e. remember how tf this thing works). 

Every command that can "add something new" starts with `add`. Every command that can "delete something" starts with `del`. 

Every command that modifies a configuration "object" starts with the name of what it is (i.e. username) followed by the id of what is being modified. 

Every command that modifies a configuration "object" tell you the order of the arguments in the command name itself. `username` expects a userid, and a new name.

All configuration is fully interactive, and your current configuration on disk is left alone until you deliberately save it.
    - However, there is no built in undo history. There is command history though (limited to current configurator session), and "destructive" commands like the '\*name' commands display the old value. 
      A command can be "undone" by running it again, but with the "old" value.

If all of this is too bothersome for you to deal with configuration, that's fine. You can just edit yaml as well. I may add other "backings" for configuration, but I'm used to yaml... 
The configurator is written in such a way that adding additional serialization formats is very straight forward. 

Additionally, the daemon mode helpfully provides messages on it's enabled configuration, and what to do to change that configuration! 
Every part of Quarterback is designed to be as "friendly" as possible, by guiding you to what it "wants" from you.

### Show me!

Clone this repository and build with `cargo build`, or download the latest release from this repository. 

The only formats that will be offered at this time are built against the `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (this does work on a Raspberry Pi 3B!) in release mode.
This produces a statically linked executable of a fairly small size. This should work on any modern Linux distribution.

There are currently two modes that can be used with Quarterback: `configurator` and `daemon`.

Configurator is the default mode, and is the interactive configurator for Quarterback.

Daemon will serve the configurator specified as a daemon.

Both modes can be provided a configuration file name, but this file must contain a valid configuration.
If this is your first time running Quarterback, don't give it a configuration file yet. You will set one later.

On your first run, the configurator will let you know you are running in `memory` mode. This mode allows you 
to make any configuration you want, but does not save anything to disk.

To save to disk use `backing yaml /path/to/yamlfile.yml` followed by `save`

All paths, even for actions, are recommended to be the **full path** to the file / executable. 
This is for the same reason as cron, to prevent issues with relative paths!

Here's a short example of creating a new action, with a 60 second timeout, and a 120 second cooldown, from a blank configuration:

```
adduser david
addrole action1role 
addaction action1 60 120 curl https://ything.net
addroleaction [roleid] [actionid]
save
```

This will then display the yaml that would be saved to disk, by default `memory` mode prints the configuration to stdout.

Now how about we save it to a file?

```
backing yaml ./qbconfig.yml
save
```

Now it is saved in the ./qbconfig.yml file! You can exit the configurator, and you can run your configuration in daemon mode!

### Then what?

Well, after all that effort configuring everything, run it as a daemon. It will now serve a very simple "API" over HTTP. It doesn't know anything at all about SSL. 

I have reverse proxies handling SSL for me everywhere, but I am not opposed to adding the feature. 
I just have no need, at this time, to have this serve HTTPS directly. 
Please use a reverse proxy for now, but feel free to open an issue (or even implement it and give me a pull request!) if this is something you would like.

The daemon will then respond to requests at the following endpoints:

Verify the Quarterback is running
This will return "Hello World" with no rate limiting

`/`

If enabled at daemon start with the `--allow-print-config` flag an admin key will be printed to stdout. This is unique to every daemon invocation.
This endpoint will return the configuration Yaml for the daemon.

`/config/[adminkey]`

Run the action

`/run/[action]/[user]/[userkey]`

Display the status of the action (does not persist daemon restarts):
Displays the stdout history from the last invocation of the action (if enabled)
This will update as the action runs to completion. 
This is disabled by default, turn it on with `actionstdout [actionid] true`

By default this will only return the start and finish times for an action.

`/status/[action]/[user]/[userkey]`

Display the 'state' of the task, running or finished only:

`/state/[action]/[user]/[userkey]`

Abort a running action, (this sends signal 15 to the process by default, signal 9 (or any other) can be sent if configured). 
Design note: You may want to ensure that whatever your actions do, can recover from this. 
This can be disabled by setting the abort signal for the action to 0.

`/abort/[action]/[user]/[userkey]`

Display the remaining time on the timeout, in seconds

`/timeout/[action]/[user]/[userkey]`

Display the remaining time on the cooldown, in seconds

`/cooldown/[action]/[user]/[userkey]`

Display a list of invocation times for a task

`/log/[aciton]/[user]/[userkey]`


Note: There is a "global" rate limit that is applied before the action cooldown is checked. 
This is configured with the --global-rate-limit-secs in daemon mode. By default this is 5 seconds.

This is to prevent bruteforce attacks that try to find valid endpoints (action, user, and key combinations).

Actions that do not exist will always return 401 Unauthorized,
the same as if the user / key combination can not execute the tasks. 
No need to track a rate limit specific to each "unknown" task! If it doesn't exist, it's "unauthorized," simple as that!

The default value of 5 seconds *should* be sufficient to prevent a denial of service by overloading Quarterback with user key hashing.

This *should* also prevent bruteforcing user keys if an attacker does know a valid action / user combination.
As the "keys" are hashed with argon2id this is fairly "expensive" on the server side.

If an action does exist, the global rate limit is applied to the action itself,
as checking if the action exists is "cheap" but hashing keys is "expensive."

The key, being user input exposed to the internet, needs to be fed through an argon2id hash verifier, to check if the user is authorized to execute the action. 
The "action" only needs to be checked with [SipHash13](https://doc.rust-lang.org/src/std/collections/hash/map.rs.html#3154),
which is *much* faster (i.e. less "expensive") in comparison. 

This *should* make denial of service attacks much more difficult then if the argon2id hashing was "unprotected"

TODO: Put together a test to prove that all these "shoulds" are actually true.


### Running the Daemon

My recommended configuration (TODO: SystemD service file), runs the daemon like so:

    ./quarterback daemon --config qb.yml --with-request-logging --listen-addr 10.88.0.1:4242
     ^ executable ^ mode          ^ config file ^ see whats going on          ^ where to listen (by default this is 127.0.0.1:4242)

Daemon configuration options are:

Path to the configuration file

`--config`

Enable configuration printing, this will provide an "admin key" at daemon invocation, this does not persist between runs, and is output to stdout wherever the daemon is run.

`--allow-print-config`

Output served requests to stdout, rejected requests are not logged, except where the reason for rejection is invalid user key. This may change in the future. 
By default, requests are not logged.

`--with-request-logging`

Define where to listen for requests, by default this is `127.0.0.1:4242`. This must be an IP:Port combination or daemon will fail to start.

`--listen-addr [IP]:[Port]`

This is more for debugging, but this flag will enable the [SwaggerUI](https://swagger.io/tools/swagger-ui/) for the API at /swagger

`--with-swagger-ui`

Adjust the "Global Rate Limit" that is applied before the task cooldown, by default this is 5 seconds

`--global-rate-limit-secs [timeout in seconds]`


### Future goals

TOTP and FIDO2/U2F 2FA. TOTP and FIDO2 are both *easy* from a user experience perspective. Type in a code, or press a button on a "USB Stick". Both TOTP and FIDO2 provide strong 2FA. 
I don't *really* believe that SMS or Email counts as 2FA, but I may add that as a feature if I get asked to add it. They also require additional state management on the server side.
I do believe I should be able to write the 2FA in a generic enough way that it can be "outsourced," via a configuration similar to actions. 

A "pretty" web UI for the user. I would do this by adding a "UI" flag to the action itself, allowing multiple UI implementations. 

Ability to pass data through to the executed action. This is a dangerous feature, and when implemented, I intend to, like Rust does with `mut`, make it "opt in".
One of the major goals for this project is security, in addition to simplicity. At times, these are competing goals.
Security can increase complexity, but with good engineering, can be mostly transparent to the user.

At the current time, actions are not able to receive any "outside" data through Quarterback. This is an intentional design decision at this time, as it prevents attacks based upon
malicious user input. Quarterback can do *anything*, it does not restrict you in it's usage, as long as what you need to do fits the "domain" that it is appropriate for.
At this time, commands, and all associated arguments, must be predefined in the configuration. No input can be passed down to the running "actions" at runtime. 

In the future, I may add a feature to "actions" that allow arbitrary user input. This comes with a *very strong* warning that this is dangerous. 
User input is not guaranteed to be "safe." The responsibility of ensuring input safety remains with the administrator. 

Due to how naturally "expoitable" this would be due to the nature of what Quarterback itself *is*, I am hesistant to include this as a feature, without very careful thought to the design.

### TODO List

 - All of the TODOs in the source code
 - Refactoring the source code to not be one giant file
 - Refactoring to make the source code a bit more "coherent"


### Bug Reports / Feature Improvements

Documentation clarity is an important consideration of this project. If there is any part of the documentation that is not clear, please open an issue. If there is anything ambigous, it is my goal
to ensure that it is made clear. 

Do you have an idea for a feature or improvement? Open a "Feature Improvement" issue, and I'd love to discuss it with you!

### Thanks

I thank you, the users, for using my software. I appreciate that you are using something I created, and are finding use with it. 

Support development on:

[Patreon](https://www.patreon.com/YthingLLC)

[Stripe](https://buy.stripe.com/aEU15SgTG5L09Hi9AA)

Bitcoin: bc1qvr605jye2dqlpyxpp33ttjwghmngas9g75hlwf

Ethereum: 0x0e664F5a8b193Be343BC2DC50b0C98B789eEAAf7

Monero: 49K1rUT5GPvRmuQ4zCzitodTsZ7zPH77n3GoP4Vxx8HTXTzD3UZ69MEYRdJ54BGcecLEFoxiq8B8tK3DwdKreqBJCcx2wmZ


