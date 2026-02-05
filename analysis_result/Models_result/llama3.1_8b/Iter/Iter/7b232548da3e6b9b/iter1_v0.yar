rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF D0 5A 6A 01 FF D0 E8 ?? ?? ?? ?? }
        $pattern2 = { FF D0 5A 6A 02 FF D0 E8 ?? ?? ?? ?? }

    condition:
        any of them
}