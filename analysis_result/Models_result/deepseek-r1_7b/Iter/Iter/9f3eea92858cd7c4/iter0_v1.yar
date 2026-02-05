rule Bypass_Sample
{
    meta:
        description = "Evasion bypass targeting EBP and BPF"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { FF 15 CA ?? CA CA 1E 50 }
        $pattern2 = { 8B 4F C0 ?? ?? ?? ?? BB BB F4 32 ?? ?? ?? }

    condition:
        any of them
}