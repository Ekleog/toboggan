toboggan &emsp; [![Build Status](https://travis-ci.org/Ekleog/toboggan.svg?branch=master)](https://travis-ci.org/Ekleog/toboggan)
========

`toboggan` is a sandboxing program that asks the user when the sandboxed program
tries to do something unexpected, allowing for incomplete policies.


Usage
-----

You need `zenity` installed, for the GUI asking whether to allow the syscall.

```sh
cargo build
target/debug/toboggan -c config.json -- tee /nix/store/fubar
```

TODO: Explain it better


Installation
------------

TODO: Write installation documentation and how to run tests


Troubleshooting
---------------

Be it a support request, a bug, a lack in documentation or anything else that
doesn't just work as expected, please report it as a [GitHub
issue](https://github.com/Ekleog/toboggan/issues/new).

If you don't have a github account, you can also contact me by email at
leo@gaspard.io or on IRC at freenode, chan
[`#toboggan`](https://webchat.freenode.net/?channels=toboggan).


Contribute
----------

If you feel like writing some code for `toboggan`, you can follow the following
process:

1. Fork
2. Clone your fork
3. Create a work branch: `git checkout -b my-new-idea`
4. Commit your changes: `git commit -am "Make it do my new idea"`
5. Push to your fork: `git push origin my-new-idea`
6. Submit a pull request

If you don't have or want a github account, I also accept patches at
leo@gaspard.io .


History
-------

 * 2016-12-25: Project launch


License
-------

`toboggan` is licensed under GPLv3, please see the file called `LICENSE.md`.


Credits
-------

 * Leo Gaspard <leo@gaspard.io>
