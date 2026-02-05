rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8BFF C8 ?? ?? ?? ?? E8 FF FC00000 }
        $pattern1 = { FF7508 83C4 ?? ??.6A5A8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF7508 8B45 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83C4 ?? }

    condition:
        any of them
}