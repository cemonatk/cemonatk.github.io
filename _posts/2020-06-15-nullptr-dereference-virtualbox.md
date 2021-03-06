---
title: 12 Years Old NullPtr Dereference That We Found on Oracle VM VirtualBox
---

I and [Fatih](https://www.linkedin.com/in/fatiherdogan1) found a “Null Pointer Dereference” bug on a header file of Oracle VM VirtualBox version 6.1.6. This post is shared on his [blog](https://medium.com/@fecassie) as well. 

To enumerate the input surface of the application, a simple fuzzer was developed.

Then, we reported the issue via root cause to the vendor.
This issue has been fixed and addressed in version 6.1.6. More detailed information can be found on the following ticket link.

[https://www.virtualbox.org/ticket/19579](https://www.virtualbox.org/ticket/19579)

## Simple Argument Fuzzer

To enumerate the input surface of the binary, we used an in-house built script. It extracts sub-commands and arguments by looking the output of each internalcommand like; loadmap, sethdparentuuid, dumphdinfo etc.

Our script creates possible subsets of each of internalcommands without any proper output purposes. On the gif below, how our script processes an example internalcommand is shown.

![]({{ site.url }}/assets/virtualbox/poc-1.gif)

> The script uses the proper values by parsing the config.yaml file.
```yaml
filepath: "./" 
filename: "filename" 
fileformat:
- VDI
- VMDK
- VHD
- RAW
inputfile: "filename"
outputfile: "filename"
uuid: "{ded05829-f34d-4881-9cac-fc5ad72d23c1}"
vmname: "HTC One"
diskname: "" 
list of partition numbers: "X"
todo: "X" 
password: ""
seconds: "1"
-format:
- -VDI
- -VMDK
- -VHD
- -RAW 
internalcommands:
- loadmap
- loadsyms
- sethduuid
- sethdparentuuid
- dumphdinfo
- listpartitions
- converttoraw
- converthd
- modinstall
- moduninstall
- debuglog
- passwordhash
- gueststats
```


Then baby fuzzer generates pre-payloads, hence it can pass the expected input values within the binary.

The pre-payloads which are generated by babyfuzzer are saved into a text file to be used in the fuzzing step.

In the fuzzing step, for each proper inputs in the pre-payloads text file are edited by replacing the 
“\{\{  - DUMMY  - \}\}” string with many dummy payloads.

![]({{ site.url }}/assets/virtualbox/poc-2.gif)

> While every dummy payload is executed, our crash monitor script traces for the “Segmentation Fault -11” errors.

Those bunch of codes mentioned above can be found on the GitHub repository.

[https://github.com/Vulnerability-Playground/VirtualBox-NullPTR/](https://github.com/Vulnerability-Playground/VirtualBox-NullPTR/)
## Root Cause Analysis

We chose the following crasher command, and did a root cause analysis: 

**“VBoxManage internalcommands repairhd -format karray fireh”**

To do a backtrace analysis we checked “VBoxManage.cpp” since virtualbox is an open source project then we found out how internalcommands argv values are used.

![]({{ site.url }}/assets/virtualbox/rc1.png)

As seen on the screenshot above, the handler functions are mapped with the argv parameters.

[https://www.virtualbox.org/browser/vbox/trunk/src/VBox/Frontends/VBoxManage/VBoxManage.cpp#L100](https://www.virtualbox.org/browser/vbox/trunk/src/VBox/Frontends/VBoxManage/VBoxManage.cpp#L100)

The “internalcommands” is mapped to the “handleInternalCommands” hence we checked that one.

[https://www.virtualbox.org/browser/vbox/trunk/src/VBox/Frontends/VBoxManage/VBoxInternalManage.cpp#L2594](https://www.virtualbox.org/browser/vbox/trunk/src/VBox/Frontends/VBoxManage/VBoxInternalManage.cpp#L2594)

![]({{ site.url }}/assets/virtualbox/rc2.png) 

Since “pszCmd” equals to “repairhd”, “CmdRepairHardDisk” function called by passing the following arguments.

> “a->argc — 1, &a->argv[1], &a-argv[1], a->virtualBox, a-session”

As seen in the source code of “CmdRepairHardDisk”, the expected program flow would be running properly until the following line.

```cpp
vrc = VDRepair(pVDIfs, NULL, image.c_str(), format.c_str(), fFlags);
```

![]({{ site.url }}/assets/virtualbox/rc3.png)

Our “format.c_str()” is passed into VDRepair() as 4th parameter as a pointer which is named “pszBackend”. Therefore, we checked it in the source code of the function.

![]({{ site.url }}/assets/virtualbox/rc4.png)

As seen on the screenshot above, the value which is pointed “pszBackend” is passed into vdFindImageBackend function as 1st argument.
The returned value of this function is set to “rc” variable in the same line as follows.

```cpp
rc = vdFindImageBackend(pszBackend, &pszBackend);
```

As seen on the screenshot below, the vdFindImageBackend() function returns rc which is set to VINF_SUCCESS on the following line.

```cpp
int rc = VINF_SUCCESS;
```

![]({{ site.url }}/assets/virtualbox/rc5.png)

As seen on the source code of the “err.h” below, VINF_SUCCESS is set to 0 (zero).

![]({{ site.url }}/assets/virtualbox/rc6.png)

This means rc equals to 0.

As seen on the “VD.cpp” rc passed into the “RT_SUCCESS()” function in the following line.

```cpp
If (RT_SUCCESS(rc))
```

![]({{ site.url }}/assets/virtualbox/rc7.png)

RT_SUCCESS is defined in the “vbox/trunk/include/iprt/errcore.h” as “RT_LIKELY(RT_SUCCESS_NP(rc))” so “rc” value is passed into the RT_SUCCESS_NP() which is defined on the following piece of code.

![]({{ site.url }}/assets/virtualbox/rc8.png)

The piece of code above has two conditions:


#### 1. If “RTERR_STRICT_RC” is defined before then the following works.

The following line calls success() method.

```cpp
# define RT_SUCCESS_NP(rc) ( RTErrStrictType(rc).success() )
```

![]({{ site.url }}/assets/virtualbox/rc9.png)

In the constructer of “RTErrStrictType()”, protected, the value of m_rc is initialized as 0 (zero) in the following piece of code since it is int32_t.

![]({{ site.url }}/assets/virtualbox/rc10.png)

Then the success() method always returns “True” since it checks 0≥0.


#### 2. If it is not defined before then the following works.

“VINF_SUCCESS” is set to “0” as we saw on the following file before.

![]({{ site.url }}/assets/virtualbox/rc11.png)

Then the macro becomes always “True” since it is always 0≥0.

```cpp
# define RT_SUCCESS_NP(rc) (int)(rc) >= VINF_SUCCESS
```

It is always True, hence it gets crashed whenever it is dereferenced since backend object remains as NULL pointer.

## Conclusion

After root cause analysis of the bug, we raised the ticket on virtualbox.org below.

[https://www.virtualbox.org/ticket/19579](https://www.virtualbox.org/ticket/19579)

Just after creating this ticket, we searched online (site:www.virtualbox.org “Segmentation fault” “VBoxManage”) and saw similar Segmentation fault reports.

Some of them are shared below:
- 12 years old: [https://www.virtualbox.org/ticket/2184](https://www.virtualbox.org/ticket/2184)
- 3 years old: [https://www.virtualbox.org/ticket/16603](https://www.virtualbox.org/ticket/16603)

Diff can be found on the following link:
[https://www.virtualbox.org/changeset/84328/vbox](https://www.virtualbox.org/changeset/84328/vbox)

![]({{ site.url }}/assets/virtualbox/rc12.png)

EOF.
