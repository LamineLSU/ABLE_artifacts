rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting exit paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A ?? ???? }  # TEST EAX followed by JE and a call with offset
        $pattern1 = { 33C9 0F 84 8B 45 FC ??? }    # XOR EC,EC followed by a conditional jump
        $pattern2 = { FF75 08 E8 C8 FFFF ???? }      # Push operation and a function call with displacement

    condition:
        any of them
}