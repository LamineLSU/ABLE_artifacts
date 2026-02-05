rule CustomInstructionPattern
{
    meta:
        description = "Matches three distinct instruction sequences with address wildcards"
        cape_options = true

    strings:
        $a = { E8 ?? ?? ?? ?? 85 C0 }
        $b = { 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $c = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        all of them
}