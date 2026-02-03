+++
date = '2026-02-02'
draft = false
title = 'CyberEdu dumb-discord Writeup'
ShowToc = true
tags = ["CyberEdu", "misc"]
+++

## Challenge overview

Well here is an example of a funny discord bot.

_PS: Please note that the IP:PORT received is not needed to solve the challenge and nothing will answer there. _

## Identifying the vulnerabilities

The script, decompiled:

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: server.py
# Bytecode version: 3.6rc1 (3379)
# Source timestamp: 2020-12-02 02:30:35 UTC (1606876235)

from discord.ext import commands
import discord
import json
from discord.utils import get

def obfuscate(byt):
    mask = b'ctf{tryharderdontstring}'
    lmask = len(mask)
    return bytes((c ^ mask[i % lmask] for i, c in enumerate(byt)))

def test(s):
    data = obfuscate(s.encode())
    return data
intents = discord.Intents.default()
intents.members = True
cfg = open('config.json', 'r')
tmpconfig = cfg.read()
cfg.close()
config = json.loads(tmpconfig)
token = config[test('\x17\x1b\r\x1e\x1a').decode()]
client = commands.Bot(command_prefix='/')

@client.event
async def on_ready():
    print('Connected to bot: {}'.format(client.user.name))
    print('Bot ID: {}'.format(client.user.id))

@client.command()
async def getflag(ctx):
    await ctx.send(test('\x13\x1b\x08\x1c').decode())

@client.event
async def on_message(message):
    await client.process_commands(message)
    if test('B\x04\x0f\x15\x13').decode() in message.content.lower():
        await message.channel.send(test('\x13\x1b\x08\x1c').decode())
    if test('L\x13\x03\x0f\x12\x1e\x18\x0f').decode() in message.content.lower() and message.author.id == 783473293554352141:
        role = discord.utils.get(message.author.guild.roles, name=test('\x07\x17\x12\x1dFBKXO\x11\x1d\x07\x17\x16\n\n\x01]\x06\x1d').decode())
        member = discord.utils.get(message.author.guild.members, id=message.author.id)
        if role in member.roles:
            await message.channel.send(test(config[test('\x05\x18\x07\x1c').decode()]))
    if test('L\x1c\x03\x17\x04').decode() in message.content.lower():
        await message.channel.send(test('7\x06\x1f[\x1c\x13\x0b\x0c\x04\x00E').decode())
    if '/s基ay' in message.content.lower():
        await message.channel.send(message.content.replace('/s基ay', '').replace(test('L\x13\x03\x0f\x12\x1e\x18\x0f').decode(), ''))
client.run(token)
```

I ran the bot locally to decode those strings, and here is the less obfuscated stuff:

```python
def obfuscate(byt):
    mask = b'ctf{tryharderdontstring}'
    lmask = len(mask)
    return bytes((c ^ mask[i % lmask] for i, c in enumerate(byt)))

def test(s):
    data = obfuscate(s.encode())
    return data
intents = discord.Intents.default()
intents.members = True
#cfg = open('config.json', 'r')
#tmpconfig = cfg.read()
#cfg.close()
#config = json.loads(tmpconfig)
#token = config[token.decode()]
token = 'haha'
client = commands.Bot(command_prefix='/')

@client.event
async def on_ready():
    print('Connected to bot: {}'.format(client.user.name))
    print('Bot ID: {}'.format(client.user.id))

@client.command()
async def getflag(ctx):
    await ctx.send('pong')

@client.event
async def on_message(message):
    await client.process_commands(message)
    if '!ping' in message.content.lower():
        await message.channel.send('pong probabil')
    if '/getflag' in message.content.lower() and message.author.id == 783473293554352141:
        role = discord.utils.get(message.author.guild.roles, name='dctf2020.cyberedu.ro')
        member = discord.utils.get(message.author.guild.members, id=message.author.id)
        if role in member.roles:
            await message.channel.send('ctf{real_flag}')
    if 'help' in message.content.lower():
        await message.channel.send('try harder!')
    if '/s基ay' in message.content.lower():
        await message.channel.send(message.content.replace('/s基ay', '').replace('/getflag', ''))
client.run(token)
```

I tried looking up for the bot based on the *user id* message.author.id included, and I found this:

![challenge-screenshot](user.png#center)

I couldn't add it to my friends list or find it in any app directories, and what worked was using the oauth2 discord bot invite through this link, which allows us to add a bot based on its id, not username: `https://discord.com/oauth2/authorize?client_id=783473293554352141&permissions=8&scope=bot`. (Permission = 8 means administrator).

To get the bot online, we launch the instance on Cyberedu.

I tried adding it to a server and adding all the proper roles, but it just wouldn't respond. Instead, it would reply to dms. I got really upset until and after I figured out you need to tag the bot before you send the message, *even if it has administrator permissions*. Where was that in the code we got, genuinely?

Anyways, we need to add the role `dctf2020.cyberedu.ro` to our bot, and get it to say `/getflag`. 

```python
if '/s基ay' in message.content.lower():
        await message.channel.send(message.content.replace('/s基ay', '').replace('/getflag', ''))
```

This line especially, repeats our message if it contains `/s基ay` and removes the `/s基ay` and `/getflag`. But the command is not case sensitive, while the blacklist is. So writing `/get/s基ayFlag`, will remove the /say and keep the `/getFlag` as a message. So would `/s基ay/Getflag` or anything like that.

We get back the encoded bytes `b'\x00\x00\x00\x00E\x10A\x0e\x00E\x02VA\x00\x0eXC\x17\x12\x17\x0b_\x03H\x05C_CAB\x1d\x0b\x07CWSAT\r[AEG\x17PVRKU\x16\x00L\x16EOZYC\x00QB]\x0bYFK\x17D\x14'` that we can decode with the python script.

![challenge-screenshot](flag.png#center)

That's it!





