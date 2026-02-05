rule SampleBypass
{
    meta:
        description = "Detects evasion and termination logic in the sample"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 55 3D 00 10 00 00 } // push ebp, cmp eax, 0x100000
        $b = { FF 75 08 E8 C8 FF FF FF } // push dword [ebp+8], call ___crtCorExitProcess
        $c = { FF 15 AC B0 41 00 }       // call ExitProcess
    condition:
        all of ($a, $b, $c)
}