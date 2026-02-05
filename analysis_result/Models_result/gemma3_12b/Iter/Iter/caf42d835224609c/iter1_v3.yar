rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 4C F2 FF FF } // lea eax, dword ptr [ebp-00000DB4h]
        $pattern1 = { E8 72 E5 FF FF } // call 02334A98h
        $pattern2 = { 0F 80 07 } // RDTSC

    condition:
        any of them
}