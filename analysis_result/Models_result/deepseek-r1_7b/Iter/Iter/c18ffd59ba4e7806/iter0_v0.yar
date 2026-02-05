rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 EC BB 5E 75 CF 00 41 A6 AD ?? 00 05 02 AD DD EB 00 00 00 5C 4E ?? AD DD EB 00 00 00 00 ?? AD DD EB 00 00 00 00 ?? AD DD EB 00 00 00 00 8B 45 EA DD }
        $pattern1 = { 6A 3F 00 00 00 3F 8D 81 8A F3 9D 9D EA EA DD EC 62 62 0C 76 98 DE E3 BF EC 00 41 A6 5F ?? ?? ?? 8B 44 CA EA }
        $pattern2 = { 6A 35 00 00 00 35 6A 00 00 00 00 00 ?? ?? ?? 8B 4D EC DD EB 0C 75 CF 00 41 A6 2B E3 BF EC 00 41 A6 5F }

    condition:
        any of them
}