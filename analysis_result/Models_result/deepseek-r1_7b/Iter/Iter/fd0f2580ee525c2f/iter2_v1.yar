rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using TEST, JZ, and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 3F ?? ?? ?? ?? ?? EA 07 EA DE }
        $pattern1 = { ?? C9 FA 62 FB ?? ?? ?? ?? ?? AC CE AC EC DA }
        $pattern2 = { 85 C0 8B 4F ?? 3C ?? 3A ?? CA ?? 6D 8D ?? ?? CD EA EA CA }

    condition:
        any of them
}