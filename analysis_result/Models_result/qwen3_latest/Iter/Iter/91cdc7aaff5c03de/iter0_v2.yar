rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 3D ?? ?? ?? ?? }  // Initial cmp to sandbox check
        $pattern1 = { 6A 00 FF 15 ?? ?? ?? ?? }  // Push 00 + ExitProcess call
        $pattern2 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }  // Call to 00407B2Bh + jump to 0040DEB6h

    condition:
        any of them
}