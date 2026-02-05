rule Targeted_Exit_Flow
{
    meta:
        description = "Detects setup code and exit calls in a targeted flow"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 70

    strings:
        $a = { 55 8B EC FF 75 08 } // Push ebp, mov ebp, push [ebp+08h] (setup code)
        $b = { E8 C8 FF FF FF 59 FF 75 08 } // Call to ___crtCorExitProcess, pop ecx, push [ebp+08h]
        $c = { FF 15 64 10 41 00 } // Call to ExitProcess@KERNEL32

    condition:
        all of ($a, $b, $c)
}