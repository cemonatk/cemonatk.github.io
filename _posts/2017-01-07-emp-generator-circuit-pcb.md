---
title: "EMP Generator Circuit on PCB: Build and Demonstration"
layout: post
date: 2017-01-07 17:19:24 +0100
---

Everything started with the [EMP scene in *Ocean's Eleven*](https://www.youtube.com/watch?v=jrA-1cG_wq4).
I knew the movie version was exaggerated, but I was curious about what a small
circuit could actually do.

While studying Electronics and Communications Engineering, I turned that
curiosity into my engineering project for the year. The idea also matched what
we were learning in [Electromagnetic Wave Theory (EMDT)](https://ogr.kocaeli.edu.tr/KOUBS/Genel/plan.cfm?FakulteiD=0208).
I wanted to build a small EMP generator on a custom PCB. Several people told me
it would not work, which made me want to try it even more.

I started by looking at ways to raise the voltage. [Electric insect-killer
rackets](https://en.wikipedia.org/wiki/Electric_flyswatter) were a useful reference because many use [cascaded diodes and capacitors
as a voltage multiplier](https://en.wikipedia.org/wiki/Voltage_multiplier). After plenty of reading and failed experiments, I
ended up using a [diode-capacitor charge pump](https://en.wikipedia.org/wiki/Charge_pump) with a transformer. [Prof. Mustafa
Çakır](https://avesis.kocaeli.edu.tr/mcakir) helped me find mistakes and improve the circuit.

![The EMP generator breadboard prototype](/assets/emp-generator-2017/breadboard-prototype.jpg)

![The assembled EMP generator PCB](/assets/emp-generator-2017/finished-pcb.jpg)

The calculations made sense, and the meter showed that I was raising the
voltage. Still, nothing happened. I tried it against an iPhone and other newer
devices (likely because of better [EMI shielding](https://en.wikipedia.org/wiki/Electromagnetic_shielding)), recorded the failures, and
eventually ran out of ideas.

One day I reached for a calculator instead. It first looked like yet another
failed test. Then I flipped the circular output coil, placed its other face
under the calculator, and tried again. The display filled with incorrect values
before the device reset itself. After all those attempts, that small change
finally made the effect visible.

![Calculator display affected by the output coil](/assets/emp-generator-2017/calculator-interference.jpg)

Here is the short demo of the finished circuit and the calculator test:

[![EMP generator circuit on a custom PCB beside a calculator](https://img.youtube.com/vi/0AXbYcZK5Zg/maxresdefault.jpg)](https://www.youtube.com/watch?v=0AXbYcZK5Zg)

Watch the demonstration: [EMP Generator Circuit on PCB](https://www.youtube.com/watch?v=0AXbYcZK5Zg)

## Behind the Scenes

I later put together a longer video from the project. It shows the breadboard
prototype, PCB layout, transfer and etching, soldering, coil winding, the
finished board, and some of the failed tests along the way.

[![PCB layout for the EMP generator circuit](https://img.youtube.com/vi/L3rPS9NVulY/maxresdefault.jpg)](https://www.youtube.com/watch?v=L3rPS9NVulY)

Watch the build video: [How to Make a Simple EMP on PCB](https://www.youtube.com/watch?v=L3rPS9NVulY)

The circuit contains a high-voltage section. I am keeping this here as an
archive of an old university project.
