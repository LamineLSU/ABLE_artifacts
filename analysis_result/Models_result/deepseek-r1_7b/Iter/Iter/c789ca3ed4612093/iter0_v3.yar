rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 DC DE EA DE EE AE CA EC CE DC AD EC DA 00 41 B8 D6 AC DF EA DC DE EA 01 BA EC EC }
        $pattern1 = { FF 15 3C F1 DC DE EA DF AD FF EE AE ED CE AE CA BE BA ED AE ED AC EC CA }
        $pattern2 = { E8 F7 25 00 DC DE EA DE EE AE CA EC CE AD FF EC DA AC DA AC DF EA DC DE EA 01 BA EC EC }

    condition:
        any of the patterns match, allowing bypass or detection.
}