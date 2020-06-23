# sqlmap ![](https://i.imgur.com/fe85aVR.png) (Code Dx Fork)

**This is a modified version of the popular penetration-testing tool [sqlmap](https://github.com/sqlmapproject/sqlmap). For more information on sqlmap, please refer to the original repository.**

This fork of sqlmap adds flags for generating reports in the Code Dx XML format. Files generated using the added functionality can be ingested directly by Code Dx.

## Usage

**Before using this fork, please read the disclaimer in the section below.**

### Quickstart

This sqlmap fork can be retrieved through Git, as in the example below, or [from the Github release packages](https://github.com/codedx/sqlmap/releases).

```
git clone --depth 1 https://github.com/codedx/sqlmap
cd sqlmap
python sqlmap.py --codedx <target-file> <... other args>
```

This fork of sqlmap has the same usage and features as the original `sqlmap`. It adds the following parameters:

```
--codedx <target-file>       Enables export of injections to the designated Code Dx XML file.
                             This includes URL, HTTP method, headers, request body, vector,
                             and other data related to the injection. Injections that are
                             detected to be false positives are ignored.

--codedx-conflict <action>   Determines what action to take if the target file already exists.
                             Has no effect if --codedx parameter is not used. Valid values
                             are (prompt, overwrite, append). If this parameter is not
                             specified, 'prompt' will be used as the default.
                             
                             Conflict checks are done when sqlmap starts; if the file exists,
                             the conflict will be handled automatically based on the conflict
                             action. If the file does not exist, the action will default to
                             'overwrite'.
```

### Modes of Operation

There are two main ways to use Code Dx XML export:

1. Have all sqlmap instances append to the same XML file. (`--codedx-conflict append`) This approach cannot be used if multiple sqlmap instances are being ran in parallel.
2. Have all sqlmap instances write to different files, and upload all XML files to Code Dx at once during an analysis. The only downside is needing to manage multiple XML files, rather than one merged file.

Both approaches are valid and indistinguishable, you do not lose any data or features by using one approach over another. Please use the appropriate mode of operation depending on whether you are running multiple sqlmap instances in parallel.

## Disclaimer

This fork has been ran through a number of test cases, and all test cases have passed manual validation. Due to the range of sqlmap features, we can't guarantee that all detected injections will be reported in all cases. When first using this fork, we recommend comparing the generated XML against the injections listed by sqlmap in the console. Please report any cases of missing results as a new issue on this repository, or send an email to us at `support@codedx.com`.

If there are no missed injections between the XML and console output, it should be safe to continue using this fork while assuming that all injections will be reported. This validation should be repeated if you make significant changes to your sqlmap configuration. (eg different set of target URLs, different set of parameters, etc.)

## Reporting Bugs

If you encounter a crash or other unexpected behavior, please open an issue on this Github repository. We will determine whether it's an issue related to our changes or a pre-existing issue with sqlmap. Depending on the cause, we may make changes here or suggest posting a new issue on the [original sqlmap repository](https://github.com/sqlmapproject/sqlmap/issues).

If there is a new feature or bugfix in sqlmap that isn't included in our fork, you can open an issue asking for us to merge in latest from sqlmap.