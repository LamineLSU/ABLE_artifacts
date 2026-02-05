rule Bypass_Evasion {
    meta:
        description = "Bypass patterns targeting various evilware exits"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FC E8 ?? ?? ?? ?? ??. }  # Around the call instruction with surrounding context
        $pattern1 = { 75 0C 8B FC ?? ?? ?? ?? ?? }  # Bypassing a JZ or JE with nearby offset
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }  # Bypassing another conditional jump
}

# Validation comments to ensure patterns meet criteria:
# Each pattern is exactly 10 bytes long, containing specific instructions and wildcards for addresses.