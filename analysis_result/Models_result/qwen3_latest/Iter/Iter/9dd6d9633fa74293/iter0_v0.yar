rule CRT_Exit_Call {
    meta:
        description = "Detects calls to CRT exit functions such as exit() or _exit() in C runtime libraries."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // push ebp, mov ebp, push [ebp+08], call ...
        $b = { 59 FF 15 ?? ?? ?? ?? }               // pop ecx, call ...
        $c = { FF 75 08 E8 ?? ?? ?? ?? }            // push [ebp+08], call ...
    condition:
        any of them
}