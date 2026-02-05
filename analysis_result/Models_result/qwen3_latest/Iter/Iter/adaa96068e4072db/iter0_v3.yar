rule MaliciousCodePattern
{
    meta:
        description = "Detects malicious code patterns involving call to EAX, call to RtlFreeHeap, and push edx"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "YourName"
        date = "2023-10-05"

    strings:
        $a = { 83 C4 14 52 FF D0 } // add esp,14h; push edx; call eax
        $b = { E8 ?? ?? ?? }    // call to RtlFreeHeap (offset is wildcard)
        $c = { 52 }             // push edx

    condition:
        all of ($a or $b or $c)
}