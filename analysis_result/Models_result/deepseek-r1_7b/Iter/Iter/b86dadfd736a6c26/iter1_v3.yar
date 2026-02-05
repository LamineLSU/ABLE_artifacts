rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 54 B9 0A ?? ?? ?? ?? 8B 45 ??
                     # Matches the call and subsequent mov instruction
        $pattern1 = { F7 F1 83 FA ?? ?? ?? ?? ??
                     # Matches the conditional jump check
        $pattern2 = { E8 CE 74 ?? ?? ?? ?? ?? 
                     # Matches a potential bypass around a different instruction path
    condition:
        any of them
}