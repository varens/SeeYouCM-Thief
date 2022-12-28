
```
___________
                   /.---------.\`-._
                  //          ||    `-._
                  || `-._     ||        `-._
                  ||     `-._ ||            `-._
                  ||    _____ ||`-._            \
            _..._ ||   | __ ! ||    `-._        |
          _/     \||   .'  |~~||        `-._    |
      .-``     _.`||  /   _|~~||    .----.  `-._|
     |      _.`  _||  |  |23| ||   / :::: \    \
     \ _.--`  _.` ||  |  |56| ||  / ::::: |    |
      |   _.-`  _.||  |  |79| ||  |   _..-'   /
      _\-`   _.`O ||  |  |_   ||  |::|        |
    .`    _.`O `._||  \    |  ||  |::|        |
 .-`   _.` `._.'  ||   '.__|--||  |::|        \
`-._.-` \`-._     ||   | ":  !||  |  '-.._    |
         \   `--._||   |_:"___||  | ::::: |   |
          \  /\   ||     ":":"||   \ :::: |   |
           \(  `-.||       .- ||    `.___/    /
           |    | ||   _.-    ||              |
           |    / \.-________\____.....-----'
           \    -.      \ |         |
            \     `.     \ \        |
 __________  `.    .'\    \|        |\  _________
    SeeYouCM   `..'   \    |        | \   Thief
                \   .'    |       /  .`.
                | \.'      |       |.'   `-._
                 \     _ . /       \_\-._____)
                  \_.-`  .`'._____.'`.
                    \_\-|             |
                         `._________.'
```
# SeeYouCM Thief

Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials. 

This fork adds the ability to specify a file with a list of phone IPs and removes any subnet reverse lookup operations.

## Blog 
https://www.trustedsec.com/blog/seeyoucm-thief-exploiting-common-misconfigurations-in-cisco-phone-systems/

## Usage

Specify an IP address for a single phone, optionally saving its configuration file to a given directory:

`./thief.py <phone-ip> [--verbose|-v] [--save|-s <dir-to-save-conf-files>]`

Same as above but performed on a list of phone IPs:

`./thief.py <phone-ip-list-file> [--verbose|-v] [--save|-s <dir-to-save-conf-files>]`

## Setup
`python3 -m pip install -r requirements.txt`
