rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific trace points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B16 50 51 FFD2 ?? ?? }
        $pattern1 = { 8B45 FC 8B4D ?? ?? ???? 5E 5D ?? }
        $pattern2 = { 56 push ebp pop ?? 8B45 8B45 ret }

    condition:
        any of them
}