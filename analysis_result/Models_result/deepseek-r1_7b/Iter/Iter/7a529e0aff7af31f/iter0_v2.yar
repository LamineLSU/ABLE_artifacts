rule EvasionBypass_Patterns {
    meta:
        description = "Evasion bypass detection: calls bypassed before ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE ?? 5A ?? EB ?? ED ?? EA ?? ?? E8 25 05 00 00 ?? CA 00 3D 66 7F ?? 00 3D 61 F8 ?? E9 B5 FC FF FF ?? EC DD EB 04 ?? EB ?? EB ?? }
        $pattern1 = { FF 15 2C A1 3D 00 ?? CA DD 00 3D A1 2C ?? 5F EB ?? E8 C8 FF FF FF ?? CA DD 00 3D A0 A0 ?? EB EB ?? EB ?? EB ?? }
        $pattern2 = { FF 15 AC B0 41 00 ?? CA DD 00 41 B0 AC ?? 5F EB ?? E8 C8 FF FF FF ?? CA DD 00 3D A0 A0 ?? EB EB ?? EB ?? EB ?? }
    condition:
        any of them
}