rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting strategic exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 55 8B EC EA 00 00 00 00 00 40 10 7E }
        $pattern1 = { 00 3D F6 C9 FF 72 6A 9E C8 03 } // Example of a conditional check
        $pattern2 = { 00 55 8B EC 83 F8 1E AD FF 00 40 11 2D }

    condition:
        any of them
}