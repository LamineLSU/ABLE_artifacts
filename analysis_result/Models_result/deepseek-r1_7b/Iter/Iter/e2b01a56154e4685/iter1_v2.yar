rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - focused on specific JE+TEST EAX sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 4D FC EC }
        $pattern1 = { 83 F8 74 12 6A 5B 5A 8B 4E 9D F8 }
        $pattern2 = { 8B 4D FC 00 0F 84 8B 4F CF EF 5F CE }

    condition:
        any of them
}