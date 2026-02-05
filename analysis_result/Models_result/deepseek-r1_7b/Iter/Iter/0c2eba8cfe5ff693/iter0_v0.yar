rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection rules targeting memory and stack protection"
        cape_options = "bp0=$Bypass0+0,action0=skip,bp1=$Bypass1+0,action1=skip,bp2=$Bypass2+0,action2=skip,count=0"

    strings:
        $Bypass0 = { [8 5 C0 0F 84 ?? ?? ?? ?? 8B EC ] }
        $Bypass1 = { [E 8 FF ?? ?? ?? ?? ?? ?? ] }
        $Bypass2 = { [8 B FF 55 8B EC 0F 84 ?? ?? ?? ?? ] }

    condition:
        any of them
}