rule Bypass_Evasion
{
    meta:
        description = "Malware evasion bypass using conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 03 C3 ?? ?? E8 CE 8B EC }
        $pattern2 = { FF 75 08 8C 8F FF FF 8B EC ?? }

    condition:
        any of them
}