rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 C4 83 C1 04 3B 4D FC 73 22 } // CMP ECX, [ebp-04h] + JNC
        $pattern1 = { FF 15 F0 50 61 00 } // Call to CloseHandle
        $pattern2 = { FF 15 18 50 61 00 } // Call to CryptReleaseContext

    condition:
        any of them
}