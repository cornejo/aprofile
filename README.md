# aprofile
Simple python script to allow the creation and downloading of apple development profiles

This code was based on https://github.com/kinglon/buyer which was based on https://github.com/fastlane/fastlane/blob/master/spaceship/

I got tired of using fastlane as:

- it lacks support for things I need (which exist in PRs that have never been merged)
- it's written in ruby, which I don't care to learn
- it has a lot more features and complexity than I want to deal with

So I made aprofile, which creates+downloads profiles with minimal fuss.


# Installation

First install the requirements:

`pip install -r requirements.txt`

Then configure your run by copying the config.py.example file into config.py and adding in the settings you want.

Then you can run the script directly, `./main.py`


# Configuration

The config file should be pretty self explanatory.


# 2fa

As apple has 2fa, which sends a code to apple devices, there needs to be a mechanism for having this code alert you that a 2fa code is required. Currently that's implemented in 2fa_commandline.py which will simply ask for it on the command line. Other implementations may send a message on signal, or discord, or telegram, or any other mechanism. To change behaviour, just create a new script and have the config point at it. You can even specify arguments. The script should return a very simple JSON encoded output containing the code. Anything else will be considered a failure.

