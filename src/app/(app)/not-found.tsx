import { OperatorErrorScreen } from "@/components/errors/OperatorErrorScreen";

export default function AppNotFound() {
  return (
    <OperatorErrorScreen
      info={{
        kind: "not-found",
        title: "We couldn't find that",
        description:
          "The page or resource you tried to open doesn't exist or is no longer available.",
        action: "home",
      }}
    />
  );
}
