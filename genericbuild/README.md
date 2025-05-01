# CoreDNS IP Destination Guard Deployment

This folder provides a simple build script that fetches the configured CoreDNS version,
builds it and creates the actual *coredns-ip-destination-guard* binary. You can use that
binary together with *coredns-ip-destination-guard.service* and *Corefile* to get started
with your generic installation. The service assumes you place all files in the
*/opt/coredns-ip-destination-guard* folder, but you can easily change that.

You can use the *plugin.cfg* to configure the CoreDNS build if you like.

Afterward, just use the *build.sh* script to trigger the build, it'll start downloading
everything necessary, execute the corresponding steps and creates the actual binary.

## Some details

The build will create a *src/* folder, using it as target for all dependencies. If anything
goes wrong, you can check the *src/* folder for any issues and debug it.

If you want to have a clean build, you can simply delete the *src/* folder as well as any
existing *coredns-ip-destination-guard* binaries.
