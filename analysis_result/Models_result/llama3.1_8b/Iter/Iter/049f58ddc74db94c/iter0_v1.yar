rule Bypass_Candidate_1 {
    meta:
        description = "Evasion bypass candidate 1"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 ?? ?? ?? ?? 59 FF 75 08 }

    condition:
        any of them
}