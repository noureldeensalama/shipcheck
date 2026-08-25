/**
 * Plain-language explanations shared by every license-checking backend.
 * Written for builders with zero legal or security background: short
 * sentences, concrete consequences, no jargon without an immediate gloss.
 */

export function licenseWhyStrong(label: string): string {
  return (
    `'${label}' is a "share your source" license: if your app is built on it, the law can require ` +
    `you to publish your entire app's source code too — including all the secret sauce you wrote.`
  );
}

export function licenseWhyWeak(): string {
  return (
    `This license only asks you to share your changes if you edit the package's own code. ` +
    `Using it normally is usually fine — just don't copy its code into yours.`
  );
}

export function licenseWhyUndeclared(source: string): string {
  return (
    `${source} has no license listed for this package. With no license, the default rule is ` +
    `"all rights reserved" — meaning you're not actually allowed to use it until you check with the author.`
  );
}

export function licenseWhyLookupFailed(source: string): string {
  return (
    `We couldn't reach ${source} right now to look up this package's license. ` +
    `Until someone checks it, treat it as unknown rather than fine.`
  );
}

export function licenseFixStrong(depName: string): string {
  return (
    `Look for a similar package with a normal commercial-friendly license (MIT, Apache, BSD), ` +
    `or talk to a lawyer before shipping with '${depName}' in the app.`
  );
}

export function licenseFixWeak(depName: string): string {
  return `Just use '${depName}' as-is from the package manager — don't copy or edit its code into your project.`;
}

export function licenseFixUndeclared(depName: string): string {
  return (
    `Open '${depName}'s page or repository and look for a LICENSE file. ` +
    `If there isn't one, swap it for a package that clearly says it's okay to use.`
  );
}
