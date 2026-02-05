rule EvasionBypass
{
    meta:
        author = "RedTeam"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        date = "2023-10-05"
        description = "Bypasses evasion detection by skipping critical code segments."

    strings:
        $a = { 85 C0 74 12 ?? ?? ?? ?? 8D 95 F0 FE FF FF } // Test + short jump + lea
        $b = { 85 C0 0F 84 33 FD FF FF ?? ?? ?? ?? 8B 85 F0 FE FF FF } // Test + long jump + mov
        $c = { E8 25 05 00 00 85 C0 } // Call to function + test

    condition:
        all of ($a, $b, $c)
}