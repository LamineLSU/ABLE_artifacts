rule Bypass_Sample
{
    meta:
        description = "Evasion pattern detection involving conditional jumps and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 7D FC 00 75 08 }  // cmp [ebp-04h], 0x00 followed by jne
        $pattern1 = { FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? }  // call to function, push, call to another function
        $pattern2 = { 83 7D FC 00 75 08 FF 15 ?? ?? ?? ?? }  // cmp, jne, call to exit process

    condition:
        any of them
}