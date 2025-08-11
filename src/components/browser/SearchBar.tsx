import React, { useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Lock, X, Search, Globe } from "lucide-react";

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  placeholder?: string;
  className?: string;
  userAccessLevel?: number;
}

const SearchBar: React.FC<SearchBarProps> = ({
  value,
  onChange,
  onSubmit,
  placeholder = "Enter URL or search...",
  className = "",
  userAccessLevel = 1,
}) => {
  const inputRef = useRef<HTMLInputElement>(null);

  // Test focus on mount
  useEffect(() => {
    // console.log('SearchBar mounted, input ref:', inputRef.current);
    if (inputRef.current) {
      // console.log('Input element found');
    }
  }, []);

  // Smart URL/Search detection helper function
  const isValidUrl = (input: string): boolean => {
    // Check if it looks like a URL
    if (input.startsWith("http://") || input.startsWith("https://")) {
      return true;
    }

    // Check if it has a domain-like structure (contains a dot and no spaces)
    if (input.includes(".") && !input.includes(" ")) {
      // Simple domain pattern check
      const domainPattern =
        /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      const parts = input.split("/");
      const domain = parts[0];

      // Check if the domain part looks valid
      if (domainPattern.test(domain)) {
        return true;
      }
    }

    // Check for localhost or IP addresses
    if (
      input.startsWith("localhost") ||
      input.match(/^\d+\.\d+\.\d+\.\d+(:\d+)?/)
    ) {
      return true;
    }

    return false;
  };

  const getInputType = (): "url" | "search" | "empty" => {
    if (!value.trim()) return "empty";
    if (isValidUrl(value.trim())) return "url";
    return userAccessLevel >= 2 ? "search" : "url"; // Level 1 treats everything as URL
  };

  const getIconAndColor = () => {
    const inputType = getInputType();
    switch (inputType) {
      case "search":
        return {
          icon: <Search className="h-4 w-4 text-blue-600 mr-3 flex-shrink-0" />,
          borderColor: "focus-within:border-blue-400",
        };
      case "url":
        return {
          icon: (
            <Globe className="h-4 w-4 text-emerald-600 mr-3 flex-shrink-0" />
          ),
          borderColor: "focus-within:border-emerald-400",
        };
      default:
        return {
          icon: (
            <Lock className="h-4 w-4 text-emerald-600 mr-3 flex-shrink-0" />
          ),
          borderColor: "focus-within:border-blue-400",
        };
    }
  };

  const getButtonText = (): string => {
    const inputType = getInputType();
    if (inputType === "search") return "Search";
    return "Go";
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit();
  };

  const handleClear = () => {
    onChange("");
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      onSubmit();
    }
  };

  const handleContainerClick = (e: React.MouseEvent) => {
    // Ensure clicking anywhere in the search container focuses the input
    if (inputRef.current && e.target !== inputRef.current) {
      // console.log('Container clicked, focusing input');
      inputRef.current.focus();
    }
  };

  const handleInputFocus = () => {
    // console.log('✅ Input focused');
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    // console.log('✅ Input changed:', e.target.value);
    onChange(e.target.value);
  };

  const handleInputKeyPress = (_e: React.KeyboardEvent<HTMLInputElement>) => {
    // console.log('✅ Key pressed:', e.key);
  };

  const handleInputClick = (e: React.MouseEvent<HTMLInputElement>) => {
    // console.log('✅ Input clicked');
    e.stopPropagation();
  };

  const { icon, borderColor } = getIconAndColor();

  return (
    <form
      onSubmit={handleSubmit}
      className={`flex-1 flex items-center gap-3 ${className}`}
    >
      <div
        className={`flex items-center flex-1 bg-white border border-slate-300 rounded-lg px-4 py-2.5 shadow-sm hover:shadow-md focus-within:shadow-md ${borderColor} transition-all duration-200 h-10 cursor-text`}
        onClick={handleContainerClick}
      >
        {icon}
        <input
          ref={inputRef}
          value={value}
          onChange={handleInputChange}
          onFocus={handleInputFocus}
          onKeyDown={handleKeyDown}
          onKeyPress={handleInputKeyPress}
          onClick={handleInputClick}
          className="flex-1 bg-transparent text-slate-800 placeholder-slate-500 text-sm outline-none border-none p-0 m-0"
          placeholder={placeholder}
          autoComplete="off"
          spellCheck={false}
          type="text"
          tabIndex={0}
        />
        {value && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleClear}
            className="h-6 w-6 p-0 ml-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-full transition-all duration-200 flex-shrink-0"
          >
            <X className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>
      <Button
        type="submit"
        className={`${
          getInputType() === "search"
            ? "bg-blue-600 hover:bg-blue-700"
            : "bg-emerald-600 hover:bg-emerald-700"
        } text-white px-5 py-2.5 h-10 rounded-lg font-medium transition-all duration-200 shadow-sm hover:shadow-md border-0 flex-shrink-0`}
      >
        {getButtonText()}
      </Button>
    </form>
  );
};

export default SearchBar;
