rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection for VM"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 5D ?? ?? ?? ?? 8B CE ?? 0F C0 }
        $pattern1 = { 6A 5E ?? ?? ?? ?? ?? 8B CE 0F C0 ?? }
        $pattern2 = { ?? 47 ?? ?? ?? ?? ?? ?? 0F C0 }

    condition:
        any of them
}