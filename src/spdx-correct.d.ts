declare module "spdx-correct" {
  function correct(identifier: string): string | undefined;
  export default correct;
}
