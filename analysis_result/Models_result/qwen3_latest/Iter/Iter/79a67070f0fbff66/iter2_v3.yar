rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 9C 50 61 00 }  // WaitForMultipleObjects call
        $pattern1 = { FF 15 F0 50 61 00 }  // CloseHandle call
        $pattern2 = { 3B 4D FC 73 22 }   // cmp+jnc conditional check

    condition:
        any of them
}