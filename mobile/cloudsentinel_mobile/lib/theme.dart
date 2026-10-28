import 'package:flutter/material.dart';

/// Palette shared with the Streamlit console.
class AppColors {
  static const background = Color(0xFF050810);
  static const panel = Color(0xFF0B1424);
  static const panelAlt = Color(0xFF101C31);
  static const cyan = Color(0xFF00E5FF);
  static const violet = Color(0xFF7C4DFF);
  static const text = Color(0xFFE6F1FF);
  static const muted = Color(0xFF7D93AD);
  static const line = Color(0x3300E5FF);

  static const critical = Color(0xFFFF2D55);
  static const high = Color(0xFFFF9F0A);
  static const medium = Color(0xFFFFD60A);
  static const low = Color(0xFF30D158);
  static const info = Color(0xFF64D2FF);

  static Color forSeverity(String severity) {
    switch (severity.toLowerCase()) {
      case 'critical':
        return critical;
      case 'high':
        return high;
      case 'medium':
        return medium;
      case 'low':
        return low;
      default:
        return info;
    }
  }
}

ThemeData buildTheme() {
  const scheme = ColorScheme.dark(
    primary: AppColors.cyan,
    onPrimary: AppColors.background,
    secondary: AppColors.violet,
    onSecondary: Colors.white,
    surface: AppColors.panel,
    onSurface: AppColors.text,
    error: AppColors.critical,
    onError: Colors.white,
  );

  return ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    colorScheme: scheme,
    scaffoldBackgroundColor: AppColors.background,
    fontFamily: 'monospace',
    splashFactory: InkSparkle.splashFactory,
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.background,
      foregroundColor: AppColors.cyan,
      elevation: 0,
      centerTitle: false,
      titleTextStyle: TextStyle(
        color: AppColors.cyan,
        fontSize: 16,
        fontWeight: FontWeight.w700,
        letterSpacing: 2.2,
        fontFamily: 'monospace',
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: AppColors.panel,
      hintStyle: const TextStyle(color: AppColors.muted, fontSize: 13),
      labelStyle: const TextStyle(color: AppColors.muted, fontSize: 12),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 15),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: AppColors.line),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: AppColors.line),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: AppColors.cyan, width: 1.4),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: AppColors.critical),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: AppColors.cyan,
        foregroundColor: AppColors.background,
        minimumSize: const Size.fromHeight(50),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: const TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.w800,
          letterSpacing: 1.6,
          fontFamily: 'monospace',
        ),
      ),
    ),
    chipTheme: ChipThemeData(
      backgroundColor: AppColors.panel,
      selectedColor: AppColors.cyan.withValues(alpha: 0.16),
      side: const BorderSide(color: AppColors.line),
      labelStyle: const TextStyle(color: AppColors.muted, fontSize: 11.5),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(999)),
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
    ),
    dividerTheme: const DividerThemeData(color: AppColors.line, thickness: 1),
    progressIndicatorTheme: const ProgressIndicatorThemeData(
      color: AppColors.cyan,
    ),
  );
}

/// Panel with the same glass/border look as the web console.
class GlassPanel extends StatelessWidget {
  const GlassPanel({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(16),
    this.borderColor = AppColors.line,
    this.gradient,
  });

  final Widget child;
  final EdgeInsetsGeometry padding;
  final Color borderColor;
  final Gradient? gradient;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: AppColors.panel,
        gradient: gradient,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: borderColor),
        boxShadow: [
          BoxShadow(
            color: AppColors.cyan.withValues(alpha: 0.05),
            blurRadius: 22,
            spreadRadius: -8,
          ),
        ],
      ),
      child: child,
    );
  }
}
