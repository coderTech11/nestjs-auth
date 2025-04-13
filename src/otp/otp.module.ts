import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OTP } from './entities/otp.entity';
import { OTPService } from './otp.service';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [TypeOrmModule.forFeature([OTP]), JwtModule],
  providers: [OTPService],
  exports: [OTPService],
})
export class OTPModule {}
