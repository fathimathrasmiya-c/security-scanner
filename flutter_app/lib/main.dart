import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:google_fonts/google_fonts.dart';
import 'screens/dashboard_screen.dart';
import 'services/api_service.dart';

void main() {
  runApp(const SecurityScannerApp());
}

class SecurityScannerApp extends StatelessWidget {
  const SecurityScannerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider<ApiService>(
          create: (_) => ApiService(baseUrl: 'http://127.0.0.1:5000'),
        ),
      ],
      child: MaterialApp(
        title: 'AI Security Scanner',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          useMaterial3: true,
          brightness: Brightness.dark,
          scaffoldBackgroundColor: const Color(0xFF0F172A),
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFF6366F1),
            brightness: Brightness.dark,
          ),
          textTheme: GoogleFonts.interTextTheme(
            ThemeData(brightness: Brightness.dark).textTheme,
          ),
          cardTheme: CardThemeData(
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
          elevatedButtonTheme: ElevatedButtonThemeData(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF6366F1),
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
          ),
          appBarTheme: const AppBarTheme(
            backgroundColor: Color(0xFF1E293B),
            foregroundColor: Colors.white,
            elevation: 0,
          ),
        ),
        home: const DashboardScreen(),
      ),
    );
  }
}
